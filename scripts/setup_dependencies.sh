#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VCPKG_ROOT="${VCPKG_ROOT:-$HOME/vcpkg}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
ANDROID_NDK="${ANDROID_NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
QT_HOST_PREFIX="${QT_HOST_PREFIX:-$HOME/Qt/6.12.0/gcc_64}"
QT_ANDROID_PREFIX="${QT_ANDROID_PREFIX:-$HOME/Qt/6.12.0/android_arm64_v8a}"
SDKMANAGER_BIN="${SDKMANAGER_BIN:-}"

say() { printf '\n%s\n' "$*"; }
manual_steps=0

if [[ ! -r /etc/os-release ]]; then
    printf '✗ Cannot identify the Linux distribution; setup supports Ubuntu and Debian.\n' >&2
    exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != ubuntu && "${ID:-}" != debian && " ${ID_LIKE:-} " != *' ubuntu '* && " ${ID_LIKE:-} " != *' debian '* ]]; then
    printf '✗ make setup supports Ubuntu/Debian apt systems; install the listed packages manually.\n' >&2
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    printf '✗ apt-get is required on Ubuntu/Debian.\n' >&2
    exit 1
fi

say 'Installing system build tools and a full JDK (sudo may prompt for your password)...'
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake curl git ninja-build pkg-config unzip zip tar \
    openjdk-17-jdk-headless libgl1-mesa-dev libxkbcommon-x11-0 libxcb-cursor0

if [[ ! -d "$VCPKG_ROOT/.git" ]]; then
    if [[ -e "$VCPKG_ROOT" ]]; then
        printf '✗ VCPKG_ROOT exists but is not a vcpkg Git checkout: %s\n' "$VCPKG_ROOT" >&2
        exit 1
    fi
    say "Cloning vcpkg into $VCPKG_ROOT..."
    mkdir -p "$(dirname "$VCPKG_ROOT")"
    git clone https://github.com/microsoft/vcpkg.git "$VCPKG_ROOT"
fi

if [[ ! -x "$VCPKG_ROOT/vcpkg" ]]; then
    say 'Bootstrapping vcpkg...'
    "$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
fi

say 'Installing desktop manifest dependencies with vcpkg...'
"$VCPKG_ROOT/vcpkg" install --triplet x64-linux \
    --x-manifest-root "$PROJECT_ROOT" \
    --x-install-root "$PROJECT_ROOT/vcpkg_installed"

if [[ -z "$SDKMANAGER_BIN" ]]; then
    for candidate in \
        "$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" \
        "$ANDROID_SDK_ROOT/tools/bin/sdkmanager"; do
        if [[ -x "$candidate" ]]; then
            SDKMANAGER_BIN="$candidate"
            break
        fi
    done
fi
if [[ -z "$SDKMANAGER_BIN" ]] && command -v sdkmanager >/dev/null 2>&1; then
    SDKMANAGER_BIN="$(command -v sdkmanager)"
fi

if [[ -n "$SDKMANAGER_BIN" && -x "$SDKMANAGER_BIN" ]]; then
    say 'Accept Android SDK licenses when prompted, then install the Android platform, build tools, and NDK...'
    if "$SDKMANAGER_BIN" --sdk_root="$ANDROID_SDK_ROOT" --licenses; then
        if "$SDKMANAGER_BIN" --sdk_root="$ANDROID_SDK_ROOT" \
            'platform-tools' 'platforms;android-35' 'build-tools;35.0.0' 'ndk;27.2.12479018'; then
            if [[ -z "$ANDROID_NDK" ]]; then
                ANDROID_NDK="$ANDROID_SDK_ROOT/ndk/27.2.12479018"
            fi
        else
            printf '… Android SDK component installation failed; review sdkmanager output and retry.\n'
            manual_steps=1
        fi
    else
        printf '… Android SDK licenses were not accepted; review them with:\n  %s --sdk_root="%s" --licenses\n' "$SDKMANAGER_BIN" "$ANDROID_SDK_ROOT"
        manual_steps=1
    fi
else
    cat <<EOF
… Android SDK command-line tools (sdkmanager) not found. Install Google's Android command-line tools, then run:
  $ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager --sdk_root="$ANDROID_SDK_ROOT" --licenses
  $ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager --sdk_root="$ANDROID_SDK_ROOT" 'platform-tools' 'platforms;android-35' 'build-tools;35.0.0' 'ndk;27.2.12479018'
EOF
    manual_steps=1
fi

if [[ -n "$ANDROID_NDK" && -x "$VCPKG_ROOT/vcpkg" ]]; then
    if [[ -f "$ANDROID_NDK/build/cmake/android.toolchain.cmake" ]]; then
        say 'Installing Android arm64 manifest dependencies with vcpkg...'
        ANDROID_NDK="$ANDROID_NDK" "$VCPKG_ROOT/vcpkg" install \
            --triplet arm64-android \
            --overlay-triplets "$PROJECT_ROOT/triplets" \
            --x-manifest-root "$PROJECT_ROOT" \
            --x-install-root "$PROJECT_ROOT/vcpkg_installed"
    else
        printf '… Android NDK was not found at %s; Android vcpkg dependencies were skipped.\n' "$ANDROID_NDK"
        manual_steps=1
    fi
else
    printf '… Android NDK path is not available; Android vcpkg dependencies were skipped.\n'
    manual_steps=1
fi

if [[ ! -f "$QT_HOST_PREFIX/lib/cmake/Qt6/Qt6Config.cmake" || \
      ! -f "$QT_ANDROID_PREFIX/lib/cmake/Qt6/Qt6Config.cmake" ]]; then
    cat <<EOF

Manual Qt 6 setup is still required:
  1. Create/sign in to a Qt account and download the Qt Online Installer from https://www.qt.io/development/download-qt-installer-oss.
  2. Install Qt 6.12.0 for Linux desktop (GCC 64-bit) and Android arm64-v8a.
  3. Include Qt Core, Gui, Widgets, and the Qt Svg dependency, plus the Qt Android deployment/Gradle tools.
  4. Keep the default kits at:
       Desktop: $QT_HOST_PREFIX
       Android: $QT_ANDROID_PREFIX
     or pass QT_HOST_PREFIX and QT_ANDROID_PREFIX to Make.

After installing Qt, run 'make preflight-desktop' and 'make preflight-android'.
EOF
    manual_steps=1
else
    say '✓ Both Qt 6 kits are present at their configured locations.'
fi

if (( manual_steps )); then
    printf '\nAutomated setup finished with manual Android SDK/NDK and/or Qt steps remaining.\n'
else
    printf '\n✓ Command-line prerequisites and vcpkg dependencies are set up.\n'
fi
