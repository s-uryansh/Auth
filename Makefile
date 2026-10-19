# Makefile for Auth project
# Usage: make build, make test, make ui, make clean, make android

# Default target
.PHONY: all
all: build

# Vcpkg root
VCPKG_ROOT ?= ~/vcpkg

# Build directory
BUILD_DIR ?= build

# CMake toolchain
TOOLCHAIN ?= $(VCPKG_ROOT)/scripts/buildsystems/vcpkg.cmake

# Detect Android NDK
ANDROID_NDK ?=
ANDROID_SDK_ROOT ?=
QT_ANDROID_PREFIX ?= /home/s-uryansh/Qt/6.12.0/android_arm64_v8a
QT_HOST_PREFIX ?= /home/s-uryansh/Qt/6.12.0/gcc_64
ANDROID_BUILD_DIR ?= build_android_arm64

# ---------- Default (Desktop) Build ----------

.PHONY: build
build:
	@rm -rf $(BUILD_DIR)
	@cmake -B $(BUILD_DIR) -S . -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN)
	@cmake --build $(BUILD_DIR)

.PHONY: test
test: build
	@ctest --test-dir $(BUILD_DIR) --output-on-failure

.PHONY: ui
ui: build
	@./$(BUILD_DIR)/AuthQt

.PHONY: demo
demo: build
	@./$(BUILD_DIR)/AuthUI

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)

# ---------- Android Build ----------

.PHONY: android
android:
	@if [ -z "$(ANDROID_NDK)" ]; then \
		echo "ERROR: ANDROID_NDK not set. Usage: make ANDROID_NDK=/path/to/android-ndk android"; \
		exit 1; \
	fi
	@if [ -z "$(ANDROID_SDK_ROOT)" ]; then \
		echo "ERROR: ANDROID_SDK_ROOT not set."; \
		exit 1; \
	fi
	@mkdir -p $(ANDROID_BUILD_DIR)
	@ANDROID_NDK=$(ANDROID_NDK) cmake -B $(ANDROID_BUILD_DIR) -S . -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
		-DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=$(ANDROID_NDK)/build/cmake/android.toolchain.cmake \
		-DCMAKE_ANDROID_NDK=$(ANDROID_NDK) \
		-DCMAKE_ANDROID_ARCH_ABI=arm64-v8a -DCMAKE_SYSTEM_VERSION=30 \
		-DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30 \
		-DCMAKE_ANDROID_PLATFORM=android-30 \
		-DANDROID_SDK_ROOT=$(ANDROID_SDK_ROOT) \
		-DVCPKG_TARGET_TRIPLET=arm64-android \
		-DVCPKG_OVERLAY_TRIPLETS=$(CURDIR)/triplets \
		-DCMAKE_PREFIX_PATH=$(QT_ANDROID_PREFIX) \
		-DQt6_DIR=$(QT_ANDROID_PREFIX)/lib/cmake/Qt6 \
		-DQt6Core_DIR=$(QT_ANDROID_PREFIX)/lib/cmake/Qt6Core \
		-DQt6Gui_DIR=$(QT_ANDROID_PREFIX)/lib/cmake/Qt6Gui \
		-DQt6Widgets_DIR=$(QT_ANDROID_PREFIX)/lib/cmake/Qt6Widgets \
		-DQt6Svg_DIR=$(QT_ANDROID_PREFIX)/lib/cmake/Qt6Svg \
		-DQT_HOST_PATH=$(QT_HOST_PREFIX)
	@cmake --build $(ANDROID_BUILD_DIR) --target AuthQt_make_apk

.PHONY: android-clean
android-clean:
	@rm -rf $(ANDROID_BUILD_DIR)

.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Desktop targets:"
	@echo "  build      - Build all targets (AuthLib, AuthUI, AuthTests, AuthQt)"
	@echo "  test       - Build desktop targets and run the protocol test suite (ctest)"
	@echo "  ui         - Run AuthQt GUI application"
	@echo "  demo       - Run AuthUI console demo"
	@echo "  clean      - Remove build directory"
	@echo ""
	@echo "Android targets:"
	@echo "  android    - Configure and package the arm64-v8a Android APK (set ANDROID_NDK and ANDROID_SDK_ROOT)"
	@echo "  android-clean - Remove Android build directory"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make test"
	@echo "  make ui"
	@echo "  make ANDROID_NDK=/opt/android-ndk android"
