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
	@mkdir -p build_android
	@cmake -B build_android -S . -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
		-DCMAKE_ANDROID_NDK=$(ANDROID_NDK) \
		-DCMAKE_ANDROID_ARCH_x86_64=YES \
		-DCMAKE_ANDROID_PLATFORM=android-30
	@cmake --build build_android

.PHONY: android-clean
android-clean:
	@rm -rf build_android

.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Desktop targets:"
	@echo "  build      - Build all targets (AuthLib, AuthUI, AuthTests, AuthQt)"
	@echo "  test       - Run 1445 tests (ctest)"
	@echo "  ui         - Run AuthQt GUI application"
	@echo "  demo       - Run AuthUI console demo"
	@echo "  clean      - Remove build directory"
	@echo ""
	@echo "Android targets:"
	@echo "  android    - Configure and build for Android (set ANDROID_NDK path)"
	@echo "  android-clean - Remove Android build directory"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make test"
	@echo "  make ui"
	@echo "  make ANDROID_NDK=/opt/android-ndk android"