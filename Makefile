# User-facing targets:
#   make all (desktop + Android), build, test, ui, demo, clean,
#   android, android-clean, help

.DEFAULT_GOAL := all

# Build paths and toolchain overrides.
VCPKG_ROOT ?= $(HOME)/vcpkg
TOOLCHAIN ?= $(VCPKG_ROOT)/scripts/buildsystems/vcpkg.cmake
VCPKG_INSTALLED_DIR ?= $(CURDIR)/vcpkg_installed/x64-linux
BUILD_DIR ?= build
ANDROID_BUILD_DIR ?= build_android_arm64
ANDROID_APK_PATH = $(ANDROID_BUILD_DIR)/android-build/build/outputs/apk/debug/android-build-debug.apk

CMAKE_BIN ?= cmake
CXX_BIN ?= c++
CTEST_BIN ?= ctest

ANDROID_NDK ?= $(if $(ANDROID_NDK_HOME),$(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
ANDROID_SDK_ROOT ?= $(HOME)/Android/Sdk
GRADLE_USER_HOME ?= $(HOME)/.gradle
QT_ANDROID_PREFIX ?= /home/s-uryansh/Qt/6.12.0/android_arm64_v8a
QT_HOST_PREFIX ?= /home/s-uryansh/Qt/6.12.0/gcc_64

# Keep all prerequisites for the combined target ahead of its sequential builds,
# including when the caller requests parallel Make execution.
.NOTPARALLEL: all test
.PHONY: all build desktop-build test ui demo clean android android-package android-clean help
.PHONY: preflight-desktop preflight-android preflight-test

all: preflight-desktop preflight-android desktop-build android-package
	@printf '\n✓ Desktop and Android builds successful.\n  Desktop application: %s/AuthQt\n  Console demo: %s/AuthUI\n  Android APK: %s\n' \
		"$(BUILD_DIR)" "$(BUILD_DIR)" "$(ANDROID_APK_PATH)"

preflight-desktop:
	@PROJECT_ROOT="$(CURDIR)" \
	 VCPKG_ROOT="$(VCPKG_ROOT)" TOOLCHAIN="$(TOOLCHAIN)" \
	 VCPKG_INSTALLED_DIR="$(VCPKG_INSTALLED_DIR)" \
	 QT_HOST_PREFIX="$(QT_HOST_PREFIX)" CMAKE_BIN="$(CMAKE_BIN)" \
	 CXX_BIN="$(CXX_BIN)" \
	 ./scripts/check_prerequisites.sh desktop

preflight-android:
	@PROJECT_ROOT="$(CURDIR)" \
	 VCPKG_ROOT="$(VCPKG_ROOT)" TOOLCHAIN="$(TOOLCHAIN)" \
	 QT_ANDROID_PREFIX="$(QT_ANDROID_PREFIX)" QT_HOST_PREFIX="$(QT_HOST_PREFIX)" \
	 ANDROID_NDK="$(ANDROID_NDK)" ANDROID_SDK_ROOT="$(ANDROID_SDK_ROOT)" \
	 GRADLE_USER_HOME="$(GRADLE_USER_HOME)" \
	 CMAKE_BIN="$(CMAKE_BIN)" \
	 ./scripts/check_prerequisites.sh android

preflight-test:
	@PROJECT_ROOT="$(CURDIR)" CTEST_BIN="$(CTEST_BIN)" \
	 ./scripts/check_prerequisites.sh test

# ---------- Desktop ----------

build: desktop-build
	@printf '\n✓ Desktop build successful.\n  Qt application: %s/AuthQt\n  Console demo: %s/AuthUI\n' \
		"$(BUILD_DIR)" "$(BUILD_DIR)"

desktop-build: preflight-desktop
	@rm -rf "$(BUILD_DIR)"
	@CXX="$(CXX_BIN)" "$(CMAKE_BIN)" -B "$(BUILD_DIR)" -S . \
		-DCMAKE_TOOLCHAIN_FILE="$(TOOLCHAIN)" \
		-DCMAKE_PREFIX_PATH="$(QT_HOST_PREFIX);$(VCPKG_INSTALLED_DIR)"
	@"$(CMAKE_BIN)" --build "$(BUILD_DIR)"
	@test -f "$(BUILD_DIR)/AuthQt" -a -f "$(BUILD_DIR)/AuthUI"

test: preflight-test desktop-build
	@"$(CTEST_BIN)" --test-dir "$(BUILD_DIR)" --output-on-failure
	@printf '\n✓ Desktop build and tests successful.\n  Qt application: %s/AuthQt\n  Console demo: %s/AuthUI\n' \
		"$(BUILD_DIR)" "$(BUILD_DIR)"

ui: desktop-build
	@"$(BUILD_DIR)/AuthQt"
	@printf '\n✓ Desktop application ran successfully.\n  Qt application: %s/AuthQt\n' "$(BUILD_DIR)"

demo: desktop-build
	@"$(BUILD_DIR)/AuthUI"
	@printf '\n✓ Desktop demo ran successfully.\n  Console demo: %s/AuthUI\n' "$(BUILD_DIR)"

clean:
	@rm -rf "$(BUILD_DIR)"

# ---------- Android ----------

android: android-package
	@printf '\n✓ Android APK build successful.\n  Android APK: %s\n' "$(ANDROID_APK_PATH)"

android-package: preflight-android
	@mkdir -p "$(ANDROID_BUILD_DIR)"
	@ANDROID_NDK="$(ANDROID_NDK)" "$(CMAKE_BIN)" -B "$(ANDROID_BUILD_DIR)" -S . \
		-DCMAKE_TOOLCHAIN_FILE="$(TOOLCHAIN)" \
		-DVCPKG_CHAINLOAD_TOOLCHAIN_FILE="$(ANDROID_NDK)/build/cmake/android.toolchain.cmake" \
		-DCMAKE_ANDROID_NDK="$(ANDROID_NDK)" \
		-DCMAKE_ANDROID_ARCH_ABI=arm64-v8a -DCMAKE_SYSTEM_VERSION=30 \
		-DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30 \
		-DCMAKE_ANDROID_PLATFORM=android-30 \
		-DANDROID_SDK_ROOT="$(ANDROID_SDK_ROOT)" \
		-DVCPKG_TARGET_TRIPLET=arm64-android \
		-DVCPKG_OVERLAY_TRIPLETS="$(CURDIR)/triplets" \
		-DCMAKE_PREFIX_PATH="$(QT_ANDROID_PREFIX)" \
		-DQt6_DIR="$(QT_ANDROID_PREFIX)/lib/cmake/Qt6" \
		-DQt6Core_DIR="$(QT_ANDROID_PREFIX)/lib/cmake/Qt6Core" \
		-DQt6Gui_DIR="$(QT_ANDROID_PREFIX)/lib/cmake/Qt6Gui" \
		-DQt6Widgets_DIR="$(QT_ANDROID_PREFIX)/lib/cmake/Qt6Widgets" \
		-DQt6Svg_DIR="$(QT_ANDROID_PREFIX)/lib/cmake/Qt6Svg" \
		-DQT_HOST_PATH="$(QT_HOST_PREFIX)"
	@GRADLE_USER_HOME="$(GRADLE_USER_HOME)" "$(CMAKE_BIN)" --build "$(ANDROID_BUILD_DIR)" --target AuthQt_make_apk
	@test -f "$(ANDROID_APK_PATH)"

android-clean:
	@rm -rf "$(ANDROID_BUILD_DIR)"

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all           Build desktop then Android APK (default)"
	@echo "  build         Configure and build desktop targets"
	@echo "  test          Build desktop targets and run tests"
	@echo "  ui            Build and run AuthQt"
	@echo "  demo          Build and run AuthUI console demo"
	@echo "  clean         Remove desktop build directory"
	@echo "  android       Configure and package the arm64-v8a Android APK"
	@echo "  android-clean Remove Android build directory"
	@echo "  preflight-desktop Check desktop build prerequisites only"
	@echo "  preflight-android Check Android packaging prerequisites only"
	@echo "  preflight-test Check the CTest runner only"
	@echo "  help          Show this help"
	@echo ""
	@echo "Build targets check only their own prerequisites; all checks both toolchains."
