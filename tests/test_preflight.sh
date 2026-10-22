#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$ROOT_DIR/scripts/check_prerequisites.sh"
TEMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEMP_ROOT"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

assert_contains() {
    local text="$1" expected="$2" label="$3"
    [[ "$text" == *"$expected"* ]] || fail "$label: missing '$expected'"
}

make_fixture() {
    local base="$TEMP_ROOT/toolchain fixture"
    mkdir -p "$base/bin" "$base/vcpkg root/scripts/buildsystems"
    mkdir -p "$base/qt host/lib/cmake/Qt6" "$base/qt host/lib/cmake/Qt6Core"
    mkdir -p "$base/qt host/lib/cmake/Qt6Gui" "$base/qt host/lib/cmake/Qt6Widgets" "$base/qt host/bin"
    mkdir -p "$base/qt android/lib/cmake/Qt6" "$base/qt android/lib/cmake/Qt6Core"
    mkdir -p "$base/qt android/lib/cmake/Qt6Gui" "$base/qt android/lib/cmake/Qt6Widgets"
    mkdir -p "$base/qt host/lib/cmake/Qt6Svg" "$base/qt android/lib/cmake/Qt6Svg"
    mkdir -p "$base/qt android/src/3rdparty/gradle"
    mkdir -p "$base/android ndk/build/cmake" "$base/android ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
    mkdir -p "$base/android sdk/platforms/android-37.0"
    mkdir -p "$base/android sdk/build-tools/36.0.0"
    mkdir -p "$base/vcpkg installed/share/gtest"
    mkdir -p "$base/gradle home"
    cat > "$base/bin/cmake" <<'CMAKE_STUB'
#!/bin/sh
if [ "${1-}" = "--version" ]; then
    printf 'cmake version 3.24.0\n'
elif [ "${1-}" = "--build" ]; then
    [ "${FAIL_BUILD:-0}" != "1" ] || exit 42
    build_dir="$2"
    if [ "${4-}" = "AuthQt_make_apk" ]; then
        if [ "${OMIT_APK:-0}" != "1" ]; then
            apk_dir="$build_dir/android-build/build/outputs/apk/debug"
            mkdir -p "$apk_dir"
            : > "$apk_dir/android-build-debug.apk"
        fi
    else
        mkdir -p "$build_dir"
        if [ "${OMIT_DESKTOP_APP:-0}" != "1" ]; then
            printf '#!/bin/sh\nexit 0\n' > "$build_dir/AuthQt"
            chmod +x "$build_dir/AuthQt"
        fi
        printf '#!/bin/sh\nexit 0\n' > "$build_dir/AuthUI"
        chmod +x "$build_dir/AuthUI"
    fi
fi
CMAKE_STUB
    printf '#!/bin/sh\nprintf "stub compiler\\n"\n' > "$base/bin/c++"
    printf '#!/bin/sh\nprintf "git version 2.40.0\\n"\n' > "$base/bin/git"
    printf '#!/bin/sh\nprintf "openjdk version 17\\n"\n' > "$base/bin/java"
    printf '#!/bin/sh\nprintf "javac 17\\n"\n' > "$base/bin/javac"
    printf '#!/bin/sh\nprintf "ctest version 3.24.0\\n"\n' > "$base/bin/ctest"
    chmod +x "$base/bin/"*
    touch "$base/vcpkg root/vcpkg" "$base/vcpkg root/scripts/buildsystems/vcpkg.cmake"
    touch "$base/qt host/lib/cmake/Qt6/Qt6Config.cmake"
    touch "$base/qt host/lib/cmake/Qt6Core/Qt6CoreConfig.cmake"
    touch "$base/qt host/lib/cmake/Qt6Gui/Qt6GuiConfig.cmake"
    touch "$base/qt host/lib/cmake/Qt6Widgets/Qt6WidgetsConfig.cmake"
    touch "$base/qt host/lib/cmake/Qt6Svg/Qt6SvgConfig.cmake"
    touch "$base/qt host/bin/androiddeployqt"
    touch "$base/qt android/lib/cmake/Qt6/Qt6Config.cmake"
    touch "$base/qt android/lib/cmake/Qt6Core/Qt6CoreConfig.cmake"
    touch "$base/qt android/lib/cmake/Qt6Gui/Qt6GuiConfig.cmake"
    touch "$base/qt android/lib/cmake/Qt6Widgets/Qt6WidgetsConfig.cmake"
    touch "$base/qt android/lib/cmake/Qt6Svg/Qt6SvgConfig.cmake"
    touch "$base/qt android/src/3rdparty/gradle/gradlew"
    touch "$base/android ndk/build/cmake/android.toolchain.cmake"
    touch "$base/android ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++"
    touch "$base/android sdk/platforms/android-37.0/android.jar"
    touch "$base/android sdk/build-tools/36.0.0/aapt" "$base/android sdk/build-tools/36.0.0/zipalign"
    touch "$base/vcpkg installed/share/gtest/GTestConfig.cmake"
    chmod +x "$base/vcpkg root/vcpkg" "$base/qt host/bin/androiddeployqt" \
        "$base/qt android/src/3rdparty/gradle/gradlew" \
        "$base/android ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++" \
        "$base/android sdk/build-tools/36.0.0/aapt" "$base/android sdk/build-tools/36.0.0/zipalign"
}

make_fixture
FIXTURE="$TEMP_ROOT/toolchain fixture"
COMMON_ENV=(
    "PATH=$FIXTURE/bin:/usr/bin:/bin"
    "PROJECT_ROOT=$ROOT_DIR"
    "VCPKG_ROOT=$FIXTURE/vcpkg root"
    "TOOLCHAIN=$FIXTURE/vcpkg root/scripts/buildsystems/vcpkg.cmake"
    "VCPKG_INSTALLED_DIR=$FIXTURE/vcpkg installed"
    "QT_HOST_PREFIX=$FIXTURE/qt host"
    "QT_ANDROID_PREFIX=$FIXTURE/qt android"
    "ANDROID_NDK=$FIXTURE/android ndk"
    "ANDROID_SDK_ROOT=$FIXTURE/android sdk"
    "GRADLE_USER_HOME=$FIXTURE/gradle home"
)

run_checker() {
    local profile="$1"
    shift
    env "${COMMON_ENV[@]}" "$@" /bin/bash "$CHECKER" "$profile"
}

run_make() {
    env "${COMMON_ENV[@]}" \
        "CMAKE_BIN=$FIXTURE/bin/cmake" \
        "CXX_BIN=$FIXTURE/bin/c++" \
        "CTEST_BIN=$FIXTURE/bin/ctest" \
        make -C "$ROOT_DIR" "$@"
}

if [[ ! -f "$CHECKER" ]]; then
    fail "checker script is missing (expected RED before implementation)"
fi

desktop_output="$(run_checker desktop)" || fail 'desktop profile should pass without Android toolchain checks'
assert_contains "$desktop_output" '✓ CMake' 'desktop profile'
assert_contains "$desktop_output" '✓ desktop Qt' 'desktop profile'
if [[ "$desktop_output" == *'Android NDK'* ]]; then
    fail 'desktop profile must not check Android NDK'
fi

android_output="$(run_checker android 'CXX_BIN=/missing desktop compiler')" \
    || fail 'Android profile should pass without desktop compiler, Qt, or GTest checks'
assert_contains "$android_output" '✓ Android SDK' 'Android profile'
if [[ "$android_output" == *'desktop Qt'* || "$android_output" == *'GTest'* || \
    "$android_output" == *'✓ C++ compiler —'* ]]; then
    fail 'Android profile must not check desktop-only Qt, GTest, or C++ compiler'
fi

test_output="$(run_checker test)" || fail 'test profile should pass with desktop and test tools'
assert_contains "$test_output" '✓ CTest' 'test profile'
if [[ "$test_output" == *'GTest'* ]]; then
    fail 'test profile should check only the test runner; desktop profile owns GTest'
fi

all_output="$(run_checker all)" || fail 'all profile should pass with both toolchains installed'
assert_contains "$all_output" '✓ Android NDK' 'all profile'
assert_contains "$all_output" '✓ desktop Qt' 'all profile'

missing_output=''
if missing_output="$(run_checker desktop 'CMAKE_BIN=/path with spaces/missing-cmake' 2>&1)"; then
    fail 'desktop profile should fail when its configured CMake is missing'
fi
assert_contains "$missing_output" '✗ CMake' 'missing CMake diagnostic'
assert_contains "$missing_output" 'CMAKE_BIN' 'missing CMake remediation'

aggregate_output=''
if aggregate_output="$(run_checker desktop \
    'CMAKE_BIN=/missing tools/cmake' 'CXX_BIN=/missing tools/c++' \
    'PATH=/missing tools' 'VCPKG_ROOT=/missing vcpkg' \
    'TOOLCHAIN=/missing vcpkg/toolchain.cmake' \
    'VCPKG_INSTALLED_DIR=/missing vcpkg packages' \
    'QT_HOST_PREFIX=/missing desktop Qt' 2>&1)"; then
    fail 'desktop profile should report multiple missing prerequisites'
fi
for label in CMake 'C++ compiler' Git 'vcpkg root' 'vcpkg executable' \
    'vcpkg CMake toolchain' 'desktop Qt' GTest; do
    assert_contains "$aggregate_output" "✗ $label" 'aggregate failure reporting'
done

missing_desktop_dir="$TEMP_ROOT/desktop-marker-build"
mkdir -p "$missing_desktop_dir"
touch "$missing_desktop_dir/keep"
if run_make build "BUILD_DIR=$missing_desktop_dir" \
    "QT_HOST_PREFIX=$TEMP_ROOT/missing desktop Qt" > "$TEMP_ROOT/build-failure.log" 2>&1; then
    fail 'make build should reject a missing desktop Qt package'
fi
[[ -f "$missing_desktop_dir/keep" ]] || fail 'failed desktop preflight must stop before the build cleanup recipe'
assert_contains "$(cat "$TEMP_ROOT/build-failure.log")" '✗ desktop Qt' 'make build gate'

missing_android_dir="$TEMP_ROOT/android-marker-build"
mkdir -p "$missing_android_dir"
touch "$missing_android_dir/keep"
if run_make android "ANDROID_BUILD_DIR=$missing_android_dir" \
    "ANDROID_NDK=$TEMP_ROOT/missing ndk" > "$TEMP_ROOT/android-failure.log" 2>&1; then
    fail 'make android should reject a missing NDK'
fi
[[ -f "$missing_android_dir/keep" ]] || fail 'failed Android preflight must stop before configure/package recipes'
assert_contains "$(cat "$TEMP_ROOT/android-failure.log")" '✗ Android NDK' 'make android gate'

missing_test_dir="$TEMP_ROOT/test-marker-build"
mkdir -p "$missing_test_dir"
touch "$missing_test_dir/keep"
if run_make test "BUILD_DIR=$missing_test_dir" \
    "CTEST_BIN=$TEMP_ROOT/missing ctest" > "$TEMP_ROOT/test-failure.log" 2>&1; then
    fail 'make test should reject a missing CTest runner'
fi
[[ -f "$missing_test_dir/keep" ]] || fail 'failed test preflight must stop before the desktop build'
assert_contains "$(cat "$TEMP_ROOT/test-failure.log")" '✗ CTest' 'make test gate'

# A desktop target should be independent of Android-only prerequisites.
desktop_build_dir="$TEMP_ROOT/desktop-only-build"
run_make build "BUILD_DIR=$desktop_build_dir" \
    "ANDROID_NDK=$TEMP_ROOT/missing ndk" > "$TEMP_ROOT/desktop-success.log" 2>&1 \
    || fail 'make build should pass when only Android prerequisites are missing'
assert_contains "$(cat "$TEMP_ROOT/desktop-success.log")" 'Prerequisite check passed (desktop)' 'desktop-only build profile'

clean_dir="$TEMP_ROOT/clean-target-build"
mkdir -p "$clean_dir"
touch "$clean_dir/keep"
run_make clean "BUILD_DIR=$clean_dir" "CMAKE_BIN=$TEMP_ROOT/missing cmake" \
    > "$TEMP_ROOT/clean.log" 2>&1 || fail 'make clean should not require build tools'
[[ ! -e "$clean_dir" ]] || fail 'make clean should remove its configured build directory'
help_output="$(run_make help "CMAKE_BIN=$TEMP_ROOT/missing cmake")" \
    || fail 'make help should not require build tools'
if [[ "$help_output" == *'Prerequisite check'* ]]; then
    fail 'make help should not run toolchain preflight'
fi

android_clean_dir="$TEMP_ROOT/android-cleanup-dir"
mkdir -p "$android_clean_dir"
touch "$android_clean_dir/keep"
run_make android-clean "ANDROID_BUILD_DIR=$android_clean_dir" \
    "ANDROID_NDK=$TEMP_ROOT/missing ndk" > "$TEMP_ROOT/android-clean.log" 2>&1 \
    || fail 'make android-clean should not require Android tools'
[[ ! -e "$android_clean_dir" ]] || fail 'make android-clean should remove its configured build directory'

success_build_dir="$TEMP_ROOT/successful desktop build"
build_output="$(run_make build "BUILD_DIR=$success_build_dir")" \
    || fail 'make build should complete with working fixture tools'
assert_contains "$build_output" 'Desktop build successful' 'desktop success report'
assert_contains "$build_output" "$success_build_dir/AuthQt" 'desktop app location'
assert_contains "$build_output" "$success_build_dir/AuthUI" 'console app location'

failed_build_dir="$TEMP_ROOT/failed desktop build"
failed_build_output=''
if failed_build_output="$(run_make build "BUILD_DIR=$failed_build_dir" FAIL_BUILD=1 2>&1)"; then
    fail 'make build should propagate a failing CMake build'
fi
if [[ "$failed_build_output" == *'Desktop build successful'* ]]; then
    fail 'failed desktop build must not print a success report'
fi

missing_desktop_app_dir="$TEMP_ROOT/missing desktop artifact"
missing_desktop_output=''
if missing_desktop_output="$(run_make build "BUILD_DIR=$missing_desktop_app_dir" \
    OMIT_DESKTOP_APP=1 2>&1)"; then
    fail 'make build should fail if the AuthQt artifact is missing'
fi
if [[ "$missing_desktop_output" == *'Desktop build successful'* ]]; then
    fail 'make build must not report success when AuthQt is absent'
fi

test_build_dir="$TEMP_ROOT/test desktop build"
test_output="$(run_make test "BUILD_DIR=$test_build_dir")" \
    || fail 'make test should complete with working fixture tools'
assert_contains "$test_output" 'Desktop build and tests successful' 'test success report'

ui_build_dir="$TEMP_ROOT/ui desktop build"
ui_output="$(run_make ui "BUILD_DIR=$ui_build_dir")" \
    || fail 'make ui should run the fixture application successfully'
assert_contains "$ui_output" 'Desktop application ran successfully' 'ui success report'

demo_build_dir="$TEMP_ROOT/demo desktop build"
demo_output="$(run_make demo "BUILD_DIR=$demo_build_dir")" \
    || fail 'make demo should run the fixture demo successfully'
assert_contains "$demo_output" 'Desktop demo ran successfully' 'demo success report'

successful_android_dir="$TEMP_ROOT/successful android build"
android_output="$(run_make android "ANDROID_BUILD_DIR=$successful_android_dir")" \
    || fail 'make android should complete with working fixture tools'
assert_contains "$android_output" 'Android APK build successful' 'Android success report'
assert_contains "$android_output" \
    "$successful_android_dir/android-build/build/outputs/apk/debug/android-build-debug.apk" \
    'APK location'

missing_apk_dir="$TEMP_ROOT/missing android artifact"
missing_apk_output=''
if missing_apk_output="$(run_make android "ANDROID_BUILD_DIR=$missing_apk_dir" OMIT_APK=1 2>&1)"; then
    fail 'make android should fail if packaging exits successfully without an APK'
fi
if [[ "$missing_apk_output" == *'Android APK build successful'* ]]; then
    fail 'make android must not report success when the APK artifact is absent'
fi

all_build_dir="$TEMP_ROOT/combined desktop build"
all_android_dir="$TEMP_ROOT/combined android build"
all_output="$(run_make all "BUILD_DIR=$all_build_dir" \
    "ANDROID_BUILD_DIR=$all_android_dir")" \
    || fail 'make all should complete with working fixture tools'
assert_contains "$all_output" 'Desktop and Android builds successful' 'combined success report'
assert_contains "$all_output" "$all_build_dir/AuthQt" 'combined desktop app location'
assert_contains "$all_output" \
    "$all_android_dir/android-build/build/outputs/apk/debug/android-build-debug.apk" \
    'combined APK location'

printf 'PASS: prerequisite profile checks\n'
