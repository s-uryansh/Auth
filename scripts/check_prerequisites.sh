#!/usr/bin/env bash
set -u

PROFILE="${1:-}"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VCPKG_ROOT="${VCPKG_ROOT:-$HOME/vcpkg}"
TOOLCHAIN="${TOOLCHAIN:-$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake}"
VCPKG_INSTALLED_DIR="${VCPKG_INSTALLED_DIR:-$PROJECT_ROOT/vcpkg_installed/x64-linux}"
QT_HOST_PREFIX="${QT_HOST_PREFIX:-$HOME/Qt/6.12.0/gcc_64}"
QT_ANDROID_PREFIX="${QT_ANDROID_PREFIX:-$HOME/Qt/6.12.0/android_arm64_v8a}"
ANDROID_NDK="${ANDROID_NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
GRADLE_USER_HOME="${GRADLE_USER_HOME:-$HOME/.gradle}"
CMAKE_BIN="${CMAKE_BIN:-cmake}"
CXX_BIN="${CXX_BIN:-${CXX:-c++}}"
CTEST_BIN="${CTEST_BIN:-ctest}"

failures=0

ok() {
    printf '✓ %s — %s\n' "$1" "$2"
}

bad() {
    printf '✗ %s — %s\n' "$1" "$2"
    failures=$((failures + 1))
}

tool_path() {
    local name="$1" configured="$2" found
    if [[ "$configured" == */* ]]; then
        [[ -x "$configured" ]] || return 1
        printf '%s\n' "$configured"
        return 0
    fi
    found="$(command -v -- "$configured" 2>/dev/null)" || return 1
    [[ -x "$found" ]] || return 1
    printf '%s\n' "$found"
}

check_tool() {
    local label="$1" command_name="$2" remediation="$3" path
    if path="$(tool_path "$label" "$command_name")"; then
        ok "$label" "$path"
    else
        bad "$label" "'$command_name' not found or not executable; install it or set $remediation"
        return 1
    fi
}

check_cmake() {
    local path version major minor
    if ! path="$(tool_path CMake "$CMAKE_BIN")"; then
        bad CMake "'$CMAKE_BIN' not found or not executable; install CMake >= 3.20 or set CMAKE_BIN"
        return
    fi
    version="$("$path" --version 2>/dev/null)"
    if [[ "$version" =~ version[[:space:]]+([0-9]+)\.([0-9]+) ]]; then
        major="${BASH_REMATCH[1]}"
        minor="${BASH_REMATCH[2]}"
        if (( major > 3 || (major == 3 && minor >= 20) )); then
            ok CMake "$path (${major}.${minor})"
            return
        fi
    fi
    bad CMake "'$path' must be version 3.20 or newer; install a supported version or set CMAKE_BIN"
}

check_file() {
    local label="$1" path="$2" remediation="$3" kind="${4:-file}"
    if [[ "$kind" == directory && -d "$path" ]]; then
        ok "$label" "$path"
    elif [[ "$kind" == executable && -x "$path" ]]; then
        ok "$label" "$path"
    elif [[ "$kind" == file && -f "$path" ]]; then
        ok "$label" "$path"
    else
        bad "$label" "'$path' is missing or invalid; set $remediation to its installed path"
    fi
}

check_shared() {
    check_cmake
    check_tool Git git PATH
    check_file 'vcpkg root' "$VCPKG_ROOT" VCPKG_ROOT directory
    check_file 'vcpkg executable' "$VCPKG_ROOT/vcpkg" VCPKG_ROOT executable
    check_file 'vcpkg CMake toolchain' "$TOOLCHAIN" TOOLCHAIN
    check_file 'vcpkg manifest' "$PROJECT_ROOT/vcpkg.json" PROJECT_ROOT
}

check_desktop() {
    check_tool 'C++ compiler' "$CXX_BIN" 'CXX_BIN or CXX'
    check_file 'desktop Qt' "$QT_HOST_PREFIX/lib/cmake/Qt6/Qt6Config.cmake" QT_HOST_PREFIX
    check_file 'desktop Qt Core' "$QT_HOST_PREFIX/lib/cmake/Qt6Core/Qt6CoreConfig.cmake" QT_HOST_PREFIX
    check_file 'desktop Qt Gui' "$QT_HOST_PREFIX/lib/cmake/Qt6Gui/Qt6GuiConfig.cmake" QT_HOST_PREFIX
    check_file 'desktop Qt Widgets' "$QT_HOST_PREFIX/lib/cmake/Qt6Widgets/Qt6WidgetsConfig.cmake" QT_HOST_PREFIX
    check_file 'desktop Qt Svg dependency' "$QT_HOST_PREFIX/lib/cmake/Qt6Svg/Qt6SvgConfig.cmake" QT_HOST_PREFIX
    check_file GTest "$VCPKG_INSTALLED_DIR/share/gtest/GTestConfig.cmake" VCPKG_INSTALLED_DIR
}

check_android() {
    local platform found_platform=0 platform_name platform_version platform_major
    local build_tool build_version build_major found_build_tool=0
    check_file 'Android Qt' "$QT_ANDROID_PREFIX/lib/cmake/Qt6/Qt6Config.cmake" QT_ANDROID_PREFIX
    check_file 'Android Qt Core' "$QT_ANDROID_PREFIX/lib/cmake/Qt6Core/Qt6CoreConfig.cmake" QT_ANDROID_PREFIX
    check_file 'Android Qt Gui' "$QT_ANDROID_PREFIX/lib/cmake/Qt6Gui/Qt6GuiConfig.cmake" QT_ANDROID_PREFIX
    check_file 'Android Qt Widgets' "$QT_ANDROID_PREFIX/lib/cmake/Qt6Widgets/Qt6WidgetsConfig.cmake" QT_ANDROID_PREFIX
    check_file 'Android Qt Svg dependency' "$QT_ANDROID_PREFIX/lib/cmake/Qt6Svg/Qt6SvgConfig.cmake" QT_ANDROID_PREFIX
    check_file 'Qt Android deployment tool' "$QT_HOST_PREFIX/bin/androiddeployqt" QT_HOST_PREFIX executable
    if [[ -n "${JAVA_HOME:-}" ]]; then
        check_file Java "$JAVA_HOME/bin/java" JAVA_HOME executable
        check_file 'Java compiler' "$JAVA_HOME/bin/javac" JAVA_HOME executable
    else
        check_tool Java java PATH
        check_tool 'Java compiler' javac PATH
    fi
    check_file 'Android NDK' "$ANDROID_NDK" 'ANDROID_NDK, ANDROID_NDK_HOME, or ANDROID_NDK_ROOT' directory
    check_file 'Android NDK CMake toolchain' "$ANDROID_NDK/build/cmake/android.toolchain.cmake" ANDROID_NDK
    check_file 'Android NDK C++ compiler' "$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++" ANDROID_NDK executable
    check_file 'Android SDK' "$ANDROID_SDK_ROOT" ANDROID_SDK_ROOT directory

    if [[ -d "$ANDROID_SDK_ROOT/platforms" ]]; then
        for platform in "$ANDROID_SDK_ROOT"/platforms/android-*; do
            [[ -f "$platform/android.jar" ]] || continue
            platform_name="${platform##*/android-}"
            platform_version="${platform_name%%.*}"
            [[ "$platform_version" =~ ^[0-9]+$ ]] || continue
            platform_major=$((10#$platform_version))
            if (( platform_major >= 30 )); then
                found_platform=1
                break
            fi
        done
    fi
    if (( found_platform )); then
        ok 'Android SDK platform' "compatible platform (API 30+) with android.jar under $ANDROID_SDK_ROOT/platforms"
    else
        bad 'Android SDK platform' "no platform API 30+ with android.jar under '$ANDROID_SDK_ROOT/platforms'; install a platform or set ANDROID_SDK_ROOT"
    fi

    if [[ -d "$ANDROID_SDK_ROOT/build-tools" ]]; then
        for build_tool in "$ANDROID_SDK_ROOT"/build-tools/*; do
            build_version="${build_tool##*/}"
            build_major="${build_version%%.*}"
            if [[ "$build_major" =~ ^[0-9]+$ ]] && (( 10#$build_major >= 30 )) && \
                [[ -x "$build_tool/aapt" && -x "$build_tool/zipalign" ]]; then
                found_build_tool=1
                break
            fi
        done
    fi
    if (( found_build_tool )); then
        ok 'Android build-tools' "aapt and zipalign installed under $ANDROID_SDK_ROOT/build-tools"
    else
        bad 'Android build-tools' "no build-tools directory with executable aapt and zipalign under '$ANDROID_SDK_ROOT/build-tools'; install Android build-tools or set ANDROID_SDK_ROOT"
    fi

    check_file 'Qt Gradle wrapper' "$QT_ANDROID_PREFIX/src/3rdparty/gradle/gradlew" QT_ANDROID_PREFIX executable
    if [[ -d "$GRADLE_USER_HOME" && -w "$GRADLE_USER_HOME" ]]; then
        ok 'Gradle user home' "$GRADLE_USER_HOME (writable)"
    else
        bad 'Gradle user home' "'$GRADLE_USER_HOME' is not writable; set GRADLE_USER_HOME to a writable cache directory"
    fi
}

case "$PROFILE" in
    desktop)
        check_shared
        check_desktop
        ;;
    android)
        check_shared
        check_android
        ;;
    test)
        check_tool CTest "$CTEST_BIN" CTEST_BIN
        ;;
    all)
        check_shared
        check_desktop
        check_android
        ;;
    *)
        printf 'Usage: %s {desktop|android|test|all}\n' "${BASH_SOURCE[0]}" >&2
        exit 2
        ;;
esac

if (( failures )); then
    printf 'Prerequisite check failed: %d issue(s).\n' "$failures" >&2
    exit 1
fi
printf 'Prerequisite check passed (%s).\n' "$PROFILE"
