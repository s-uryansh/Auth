# Android APK Build Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Configure the Qt Widgets application and its native dependencies for Android arm64-v8a and produce an installable APK from the Makefile.

**Architecture:** Keep desktop and Android dependency discovery separate in CMake, use a vcpkg Android triplet for OpenSSL/liboqs/Argon2, and use Qt 6.12's Android executable finalization and deployment tooling to generate the APK.

**Tech Stack:** CMake 3.20+, vcpkg manifest mode, Qt 6.12 Android arm64-v8a, Android SDK/NDK r30, Gradle, OpenSSL, liboqs, Argon2.

**Spec:** [2026-10-19-auth-password-manager-android-design.md](../specs/2026-10-19-auth-password-manager-android-design.md)

## Global Constraints

- “Configure the Qt Widgets application for Android arm64-v8a using the installed Qt Android kit, Android SDK, and NDK.”
- “Build OpenSSL, liboqs, and Argon2 for the Android target ABI through the project dependency configuration; remove hardcoded host paths from targets that must cross-compile.”
- “Provide a Makefile target that configures, compiles, and packages an installable APK. Keep desktop targets functional.”
- “Do not modify QR Sync source as part of Android packaging.”
- Do not add or run automated tests unless requested; build the desktop target and APK for verification.
- Do not commit or push.

## Review Focus

- Android configuration does not resolve or link x64 Linux libraries.
- Argon2 is declared and resolved for both desktop and Android ABIs.
- Qt Android deployment includes Qt Widgets, OpenSSL, liboqs, and Argon2 shared runtime dependencies where required.
- The produced APK targets arm64-v8a and is located under the Android build directory.
- Desktop CMake configuration still locates the existing x64 dependencies and builds AuthQt.

---

### Task 1: Make native dependencies platform-aware

**Files:**
- Modify: `vcpkg.json`
- Create: `triplets/arm64-android.cmake`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: vcpkg manifest dependencies and Qt package roots supplied through CMake cache variables.
- Produces: `AuthLib` linked to OpenSSL, liboqs, and Argon2 discovered for the active target platform; GTest is a host-only dependency and is configured only on desktop.

- [x] **Step 1: Declare Argon2 as a manifest dependency**

  Add `argon2` to the existing vcpkg dependency list while retaining OpenSSL, liboqs, and GTest.

- [x] **Step 2: Define the Android arm64 vcpkg triplet**

  Create `triplets/arm64-android.cmake` with target architecture `arm64`, Android system name, static library linkage for native dependencies, and `ANDROID_ABI=arm64-v8a` configuration options.

- [x] **Step 3: Remove host-only CMake paths from AuthLib**

  Replace hardcoded include/library directories with `find_package(OpenSSL REQUIRED)`, `find_package(liboqs CONFIG REQUIRED)`, and `find_package(unofficial-argon2 CONFIG REQUIRED)`, linking `unofficial::argon2::libargon2`. Find GTest and define `AuthTests` only for desktop builds. Do not configure the console `AuthUI`, `LSanCheck`, or runnable `AuthQtApp` test targets for Android. Apply AddressSanitizer flags only to desktop targets.

- [x] **Step 4: Compile the desktop AuthQt target**

  Run: `cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=/home/s-uryansh/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-linux`

  Then run: `cmake --build build --target AuthQt`

  Expected: desktop dependencies resolve without hardcoded Argon2 paths and AuthQt links.

### Task 2: Configure Qt Android packaging

**Files:**
- Modify: `CMakeLists.txt`
- Create: `android/AndroidManifest.xml`

**Interfaces:**
- Consumes: Android-built `AuthLib`, installed Qt 6.12 arm64-v8a package, SDK, NDK, and Gradle.
- Produces: finalized `AuthQt` Android target with APK deployment settings and app identifier `org.tmps.auth`.

- [x] **Step 1: Make the Qt application target platform-specific**

  Define the shared Qt sources once. For Android, create `AuthQt` with `qt_add_executable(MANUAL_FINALIZATION)`, link Qt Widgets/Core/Gui, `AuthLib`, and liboqs, set package name `org.tmps.auth`, and call `qt_finalize_executable(AuthQt)` once. Keep the desktop `AuthQt` executable and link options separate.

- [x] **Step 2: Add the Android package manifest**

  Create `android/AndroidManifest.xml` with the application label, package-compatible activity configuration, and no unrelated permissions. Set `QT_ANDROID_PACKAGE_SOURCE_DIR` on `AuthQt` to this directory. Verify the packaged APK does not request network or shared-storage permissions.

- [x] **Step 3: Configure Android arm64-v8a with Qt and vcpkg**

  Configure with `CMAKE_TOOLCHAIN_FILE=/home/s-uryansh/vcpkg/scripts/buildsystems/vcpkg.cmake`, `VCPKG_TARGET_TRIPLET=arm64-android`, `CMAKE_ANDROID_NDK=/opt/android-ndk/android-ndk-r30`, `ANDROID_ABI=arm64-v8a`, `ANDROID_PLATFORM=android-30`, and `CMAKE_PREFIX_PATH=/home/s-uryansh/Qt/6.12.0/android_arm64_v8a`.

- [x] **Step 4: Confirm Android target generation**

  Run: `cmake --build build_android_arm64 --target help`

  Expected: `AuthQt` is available as an Android executable/deployment target, and desktop-only tests are absent.

### Task 3: Expose and build the APK from Makefile

**Files:**
- Modify: `Makefile`

**Interfaces:**
- Consumes: Android CMake configuration from Task 2 and Make variables `ANDROID_NDK`, `ANDROID_SDK_ROOT`, `QT_ANDROID_PREFIX`, and `QT_HOST_PREFIX`.
- Produces: `make android` building and packaging an arm64-v8a APK under `build_android_arm64`.

- [x] **Step 1: Replace the inconsistent Android configure flags**

  Update the `android` target to use the arm64 ABI, Android vcpkg triplet, `CMAKE_PREFIX_PATH=$(QT_ANDROID_PREFIX)`, SDK root, NDK path, and Android API 30. Default `QT_ANDROID_PREFIX` to the installed arm64 Qt kit and allow overriding it. Do not remove the user's existing Android build directory.

- [x] **Step 2: Build the Qt deployment target**

  Make the target invoke `cmake --build build_android_arm64 --target AuthQt_make_apk` after configure so Qt's generated deployment step packages the APK.

- [x] **Step 3: Run the desktop and Android build commands**

  Run: `cmake --build build --target AuthQt`

  Run: `make ANDROID_NDK=/opt/android-ndk/android-ndk-r30 ANDROID_SDK_ROOT=/home/s-uryansh/Android/Sdk QT_ANDROID_PREFIX=/home/s-uryansh/Qt/6.12.0/android_arm64_v8a QT_HOST_PREFIX=/home/s-uryansh/Qt/6.12.0/gcc_64 android`

  Expected: both commands exit successfully and an arm64-v8a `.apk` exists under `build_android_arm64`.

---
