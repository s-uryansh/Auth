# Make Preflight and Focused Code Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gate each build target on the prerequisites it needs, remove only approved non-QR redundancy, and document build and codebase knowledge in the appropriate files.

**Architecture:** A single shell preflight script resolves Make/environment overrides and validates all prerequisites before public target work. Focused helpers will centralize secure Qt input and vault wiping; the vault implementation will reuse existing RAII and shared AES-GCM sizes without changing serialized bytes. Documentation will separate user commands in README from architecture and invariants in `Agents.md`.

**Tech Stack:** GNU Make, POSIX shell, CMake, C++17, Qt 6, OpenSSL, GTest, Markdown.

**Spec:** [2026-10-22-make-preflight-and-codebase-cleanup-design.md](../specs/2026-10-22-make-preflight-and-codebase-cleanup-design.md)

## Global Constraints

- Each Make target checks only the prerequisites it needs: desktop targets check the desktop toolchain, Android packaging checks Android tooling, and `all` checks both. `help`, `clean`, and `android-clean` need no build toolchain and must remain usable without one.
- The preflight reports each check with a checkmark or cross, reports all missing or misconfigured items in one run, and exits nonzero if any check fails.
- Desktop and Android remain separately buildable. `make all` builds desktop first and Android second.
- QR Sync source is out of scope and must not be changed.
- Cleanup must preserve current program behavior and vault file compatibility.
- No commit or push is permitted.
- The README must not include direct CMake or CTest build commands.
- Do not require system-wide Gradle or `adb` for APK packaging.

## Review Focus

- A missing target-specific prerequisite must block that target, while an unrelated missing toolchain must not block it; the preflight integration test must assert both cases.
- Multiple missing paths must all be reported in one execution; the script test must assert every failed label appears.
- Paths containing spaces and Make/environment overrides must resolve as one path; the preflight tests must exercise both.
- Empty and non-ASCII Qt text must produce the same UTF-8 bytes; secure-input tests must cover both, while implementation review confirms temporary UTF-8 buffers are cleansed.
- Vault AES-GCM IV/tag sizes and serialized round-trip compatibility must remain unchanged; existing vault tests and a wire-format regression assertion must cover this.

---

### Task 1: Add target-specific toolchain preflight checks

**Files:**
- Create: `scripts/check_prerequisites.sh`
- Create: `tests/test_preflight.sh`
- Modify: `Makefile`

**Interfaces:**
- Consumes: Make variables `VCPKG_ROOT`, `TOOLCHAIN`, `VCPKG_INSTALLED_DIR`, `CMAKE_BIN`, `CXX_BIN`, `CTEST_BIN`, `ANDROID_NDK`, `ANDROID_SDK_ROOT`, `GRADLE_USER_HOME`, `QT_ANDROID_PREFIX`, `QT_HOST_PREFIX`, `BUILD_DIR`, and `ANDROID_BUILD_DIR`; Git and Java resolve through `PATH`/`JAVA_HOME`.
- Produces: `scripts/check_prerequisites.sh {desktop|android|test|all}`, accepting resolved settings as environment variables and checking only the requested profile. `desktop` checks desktop build requirements including GTest's CMake package; `android` checks Android packaging requirements; `test` checks the CTest executable and is combined with desktop preflight by `make test`; `all` checks both toolchains.

- [ ] **Step 1: Add failing shell tests for complete and incomplete prerequisite sets**

Create fixture directories and stub executables in `tests/test_preflight.sh`. Assert desktop profile checks desktop tools but ignores absent Android tools; Android profile checks Android tools but ignores desktop-only Qt; test profile checks CTest; all checks both build profiles. Multiple missing required items produce all corresponding `✗` lines, nonzero status, and actionable override names. Cover Make variable/environment overrides and paths containing spaces.

- [ ] **Step 2: Run the shell test and verify it fails because the checker does not exist**

Run: `bash tests/test_preflight.sh`
Expected: FAIL because `scripts/check_prerequisites.sh` is missing.

- [ ] **Step 3: Implement the checker with aggregate status and actionable diagnostics**

In `scripts/check_prerequisites.sh`, implement profiles: `desktop` checks CMake >= 3.20, a desktop C++ compiler, Git, vcpkg root/executable/toolchain/manifest, desktop Qt Core/Gui/Widgets and Qt Svg CMake packages, and GTest's CMake package; `android` checks CMake >= 3.20, Git, vcpkg root/executable/toolchain/manifest, Android Qt Core/Gui/Widgets and Qt Svg packages, Qt host deployment tool, Java, NDK root/toolchain/NDK C++ compiler, SDK root with at least one compatible platform containing `android.jar`, installed build-tools, Qt's bundled Gradle wrapper, and a writable Gradle user home; `test` checks the CTest executable; `all` checks both build profiles. Resolve paths in this order: passed Make variable, corresponding environment variable, documented local default. Do not check for global Gradle, `adb`, or network availability. Print a separate `✓` or `✗` line for each category, retain checking after individual failures, then exit nonzero if any required check failed.

- [ ] **Step 4: Run the shell test and verify all fixture cases pass**

Run: `bash tests/test_preflight.sh`
Expected: PASS, including aggregate failures and space-containing paths.

- [ ] **Step 5: Gate every public Make target and preserve sequential `all` behavior**

Add phony `preflight-desktop`, `preflight-android`, and `preflight-test` targets that invoke the matching checker profile with quoted resolved values. Add desktop preflight to `build`, Android preflight to `android`, and test preflight to `test`; `ui` and `demo` inherit desktop checks through `build`. Declare `.NOTPARALLEL: all` and make `all` depend on desktop preflight, Android preflight, `build`, and `android` in that order. Do not add build-tool preflight to `help`, `clean`, or `android-clean`. Remove the old Android-only inline checks now covered by the profile. Do not change target names or APK output path.

- [ ] **Step 6: Extend the integration test to prove a failed preflight blocks a target recipe**

In `tests/test_preflight.sh`, invoke `make build` with fixture overrides missing a desktop prerequisite and assert it exits nonzero before configure/build work; invoke `make android` missing an Android prerequisite and assert it exits nonzero before configure/package work; invoke `make build` with all desktop checks present but Android tools absent and assert it passes the gate. Invoke `make clean` and `make help` with all toolchain paths absent and assert both still run. Use a temporary build directory with a marker file to prove cleanup is not incorrectly gated.

- [ ] **Step 7: Run preflight and Make target-order verification**

Run: `bash tests/test_preflight.sh`
Expected: PASS.

Run: `make -n all`
Expected: desktop build commands appear before Android configure/package commands; no concurrent build invocation is emitted. Keep the `all` recipe free of recursive Make so dry-run remains non-mutating.

Run: `make clean`
Expected: cleanup succeeds without inspecting unavailable build toolchains. `make help` should print target help without invoking build-tool preflight.

### Task 2: Consolidate sensitive Qt input and vault-entry wiping

**Files:**
- Create: `ui/SensitiveData.h`
- Create: `ui/SensitiveData.cpp`
- Create: `tests/test_sensitive_data.cpp`
- Modify: `ui/AuthTab.cpp`, `ui/PasswordManagerTab.cpp`, `CMakeLists.txt`

**Interfaces:**
- Produces: `ui::secureInputBytes(const QString&) -> std::vector<std::uint8_t>`, `ui::wipeBytes(std::vector<std::uint8_t>&) noexcept`, `ui::wipeVaultEntry(auth::VaultEntry&) noexcept`, and `ui::wipeVaultEntries(std::vector<auth::VaultEntry>&) noexcept` in `ui/SensitiveData.h`.
- The Qt utility remains in the UI target and must not be linked into `AuthLib`. Keep the console demo's `std::string` input code independent.

- [ ] **Step 1: Add failing tests for UTF-8 conversion and sensitive-field clearing**

In `tests/test_sensitive_data.cpp`, assert ASCII, non-ASCII, and empty `QString` inputs convert to exact UTF-8 bytes; `wipeBytes` leaves the vector empty; `wipeVaultEntry` clears username, password, website, and salt; and `wipeVaultEntries` clears the collection. Review the implementation to confirm it cleanses allocated sensitive buffers before clearing them.

- [ ] **Step 2: Add a desktop-only `SensitiveDataTests` target and confirm the new tests fail**

Register the source in the AuthQt sources, and create a desktop GTest executable linked to Qt Core, AuthLib, and GTest. Register it with CTest. Run `cmake --build build --target SensitiveDataTests && ctest --test-dir build -R SensitiveDataTests --output-on-failure`.
Expected: FAIL to compile because the helper declarations/definitions do not exist.

- [ ] **Step 3: Implement the three helpers and replace duplicated UI call sites**

Use `QString::toUtf8()` for `secureInputBytes` and cleanse that temporary `QByteArray`; cleanse byte buffers with `OPENSSL_cleanse`; implement `wipeVaultEntry` for one entry and use it in `wipeVaultEntries`. Replace the duplicate conversion/wipe blocks in Auth and Password Manager with these helpers and preserve existing ordering of encryption, cleanup, and UI updates.

- [ ] **Step 4: Run the focused tests and compile both UI translation units**

Run: `cmake --build build --target SensitiveDataTests AuthQt && ctest --test-dir build -R SensitiveDataTests --output-on-failure`
Expected: PASS and both application targets compile.

### Task 3: Reuse vault cipher RAII and shared AES-GCM field sizes

**Files:**
- Modify: `include/auth/crypto_utils.hpp`, `include/auth/kem_utils.hpp`, `src/vault.cpp`, `ui/PasswordVaultFileStore.cpp`, `tests/test_auth.cpp`
- Modify: `CMakeLists.txt`, `tests/README.md`

**Interfaces:**
- Produces: `auth::internal::kAesGcmIvBytes == 12` and `auth::internal::kAesGcmTagBytes == 16`, declared in `crypto_utils.hpp`; KEM and vault paths consume these constants.

- [ ] **Step 1: Add a regression assertion for vault serialized field layout and round-trip behavior**

Extend `TEST_P(VaultFixture, VaultEntrySerialization)` to assert the exact big-endian serialized bytes for one fixed entry (including website, username, password, and salt) and verify deserialize/serialize stability. In the round-trip test, assert the encrypted vault retains the existing 12-byte IV + 16-byte tag prefix and decrypts to the original entry.

- [ ] **Step 2: Run the targeted vault test and verify the compatibility baseline**

Run the vault test filter through `AuthTests` (using the existing GTest naming convention).
Expected: the new serialization and encrypted-prefix assertions pass against the current implementation and establish the compatibility baseline before refactoring.

- [ ] **Step 3: Reuse `EvpCipherCtxPtr` and move shared AES-GCM constants to `crypto_utils.hpp`**

Replace manual cipher context allocation/free in `src/vault.cpp` with `auth::internal::EvpCipherCtxPtr`. Define the shared AES-GCM sizes once in `crypto_utils.hpp`, update `kem_utils.hpp` to use them for overhead, allocation, parsing, and OpenSSL controls, and update vault encryption and `PasswordVaultFileStore.cpp` minimum ciphertext validation to use them without changing byte order or contents.

- [ ] **Step 4: Run all existing protocol and vault tests**

Run: `cmake --build build --target AuthTests && ctest --test-dir build --output-on-failure`
Expected: PASS; existing vault and protocol behavior remains intact.

- [ ] **Step 5: Remove the non-terminating application launch from CTest**

The `AuthQtApp` CTest entry launches `AuthQt`, whose normal `QApplication::exec()` loop does not terminate. Remove only that `add_test` registration; keep `AuthQt` in the desktop build. Update `tests/README.md` to state that UI flows are not covered by CTest.

Run: `QT_QPA_PLATFORM=offscreen ctest --test-dir build -R '^AuthQtApp$' --timeout 2`
Expected before removal: CTest times out, confirming the invalid registration. After removal, `ctest -N` must not list `AuthQtApp`.

### Task 4: Remove verified dead build configuration and document the build/code map

**Files:**
- Modify: `Makefile`, `README.md`, `tests/README.md`, `Agents.md`, `.gitignore`
- Delete: `triplets/x64-linux.cmake`

**Interfaces:**
- README documents all public Make targets and preflight overrides for users.
- `Agents.md` describes architecture, security/storage invariants, build targets, and protected files for code contributors.

- [ ] **Step 1: Verify cleanup candidates have no in-repository consumers**

Run: `rg -n 'x64-linux\.cmake|Qt6Svg_DIR|Qt6Svg' --glob '!docs/superpowers/**' .`
Expected: no source requests a Qt Svg target directly; the Qt kit configuration and Android `Qt6Svg_DIR` argument remain because the installed Qt Widgets dependency graph needs that package.

- [ ] **Step 2: Remove only the unreferenced triplet and preserve required Qt Svg configuration**

Delete `triplets/x64-linux.cmake`. Preserve `-DQt6Svg_DIR=...` in the Android configure command because Android configuration fails without it. Leave all QR source files untouched and do not remove the active `arm64-android` triplet.

- [ ] **Step 3: Rewrite user build instructions and test instructions around Make targets**

In `README.md`, list `all`, `build`, `test`, `ui`, `demo`, `clean`, `android`, `android-clean`, and `help`; state the target-specific preflight behavior; list variables for overriding installed paths; and name the desktop and Android outputs. Remove direct CMake/CTest commands and duplicate target descriptions. In `tests/README.md`, describe suite scope and invoke it with `make test` only.

- [ ] **Step 4: Update the technical map and make it trackable**

Rewrite `Agents.md` with concise component responsibilities and data flow for Auth, `AuthLib`, Qt UI, vault file storage, and tests; document credential/vault security boundaries, locked website-index behavior, vault format compatibility, build/preflight behavior, Qt/Android setup variables, and the QR exclusion. Remove stale direct CMake build steps and delete the `Agents.md` ignore rule from `.gitignore` without staging files.

- [ ] **Step 5: Verify docs, stale references, and final workspace scope**

Run: `rg -n 'cmake --build|ctest --test-dir|x64-linux\.cmake' README.md tests/README.md Agents.md Makefile .gitignore`
Expected: no stale build instructions or deleted-file references. Confirm the required `Qt6Svg_DIR` appears in Makefile and preflight validates the matching package path.

Run: `git diff --check`
Expected: no whitespace errors. Confirm `git status --short` includes no QR source changes and no staged or committed changes.

### Task 5: End-to-end verification and final review

**Files:**
- Verify: all files listed in Tasks 1–4.

**Interfaces:**
- Consumes: the `preflight`, `test`, `build`, `android`, and `all` Make targets and all tests defined above.

- [ ] **Step 1: Run focused preflight and sensitive-data tests**

Run: `bash tests/test_preflight.sh && cmake --build build --target SensitiveDataTests AuthTests AuthQt && ctest --test-dir build --output-on-failure`
Expected: all tests pass and the Qt application builds.

- [ ] **Step 2: Verify actual Make preflight and build ordering**

Run: `make help && make -n all`
Expected: help runs without toolchain checks; the combined dry run lists desktop and Android checks before their respective builds, then desktop before Android packaging.

- [ ] **Step 3: Review the final diff against the approved spec**

Run: `git diff --check && git status --short && git diff --stat`
Expected: no whitespace errors; only specified Make, documentation, helper, test, and non-QR cleanup files are modified; no QR sources changed; no commit or push exists.
