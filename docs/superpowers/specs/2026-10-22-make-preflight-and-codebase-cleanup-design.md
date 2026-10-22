# Make Preflight and Focused Code Cleanup Design

## Goal

Make each build-oriented Make target report whether its required build
environment is ready before running its work. Keep the
desktop and Android targets independently usable, add a combined `make all`
workflow, remove only clear non-QR duplication or unused build scaffolding,
and keep user instructions in the README separate from codebase knowledge in
`Agents.md`.

## Approved decisions

- Each Make target checks only the prerequisites it needs before target work.
  Desktop build/test/run targets check desktop prerequisites, Android packaging
  checks Android prerequisites, and `all` checks both. `help`, `clean`, and
  `android-clean` do not require either build toolchain and must remain usable
  when those toolchains are absent.
- The preflight reports each check with a checkmark or cross, reports all
  missing or misconfigured items in one run, and exits nonzero if any check
  fails.
- Desktop and Android remain separately buildable. `make all` builds desktop
  first and Android second.
- QR Sync source is out of scope and must not be changed.
- Cleanup must preserve current program behavior and vault file compatibility.
- No commit or push is permitted.

## Current environment and prerequisite discovery

The local Android NDK is exported as `ANDROID_NDK_HOME` from `~/.bashrc`, with
`ANDROID_NDK_ROOT` pointing to the same directory. The SDK is installed under
`$HOME/Android/Sdk`. The Android Qt arm64 kit and host Qt kit are installed
under `/home/s-uryansh/Qt/6.12.0`.

The machine has CMake, a C++ compiler, Java, vcpkg, both Qt kits, the Android
NDK, Android SDK platform API 37, Android build-tools 36, and Qt's bundled
Gradle wrapper. It has no system Gradle or `adb`; neither should be required
for packaging an APK. The app's Android minimum and target SDK remain 30.

## Design

### Prerequisite preflight

Add a focused shell helper under `scripts/` and call it from the Makefile's
public goals before their work begins. Keep dependency checks in one place
rather than repeating shell conditions across recipes.

The preflight has focused profiles:

- Desktop: CMake at the project's supported minimum version, a C++ compiler,
  Git, vcpkg root/executable/toolchain/manifest, desktop Qt Core/Gui/Widgets,
  the Qt Svg CMake dependency used by the installed kit, and the desktop
  GTest package.
- Android: the shared CMake/Git/vcpkg requirements, Android Qt
  Core/Gui/Widgets, the Qt Svg CMake dependency used by the installed kit,
  Qt host deployment tooling, Java, the configured NDK, its CMake toolchain
  and NDK C++ compiler, and the configured SDK.
- Android SDK: at least one platform compatible with the configured compile
  SDK, including `android.jar`, and installed build-tools needed by the
  current package configuration. API 37 and build-tools 36 are installed
  locally; the check should not reject another compatible SDK installation
  solely because its platform directory has a different patch suffix.
- APK packaging uses Qt's bundled Gradle wrapper; system-wide Gradle and `adb`
  are not prerequisites. The configured Gradle user home must be writable; it
  defaults to `$HOME/.gradle` and can be changed with `GRADLE_USER_HOME`.
- Test runner: CTest. `make test` also requires the desktop profile because it
  builds the desktop test targets.

`make all` checks desktop and Android profiles. Help and cleanup targets do not
need either build toolchain.

Resolve values from Make variables and environment first, then documented
local defaults. Print a useful command or variable name beside each failed
check. Do not use network probes; vcpkg may fetch manifest dependencies during
configuration, and network availability is not a stable installation check.

Use focused preflight profiles (desktop, Android, and desktop test tools) so
each build target checks only its dependencies. Targets that only print help
or remove build directories should not be blocked by missing compiler or
Android SDK installations. `make all` checks both toolchains and keeps the
desktop and Android builds sequential without competing builds.

### Focused redundancy cleanup

Do not alter `ui/QRSyncTab.cpp` or `ui/QRSyncTab.h`.

- Share the duplicate Qt `QString` to secure byte-buffer conversion and
  temporary-text wiping used by Auth and Password Manager. Keep Qt types out
  of the protocol library; keep the console demo's `std::string` input helper
  separate.
- Reuse the existing EVP cipher-context RAII wrapper in `src/vault.cpp` and
  use shared AES-GCM IV/tag size constants where doing so does not change the
  vault wire format.
- Extract the repeated vault-entry sensitive-field wipe loop in
  `PasswordManagerTab.cpp` into a single helper.
- Remove the unreferenced `triplets/x64-linux.cmake` file. Keep the Android
  `Qt6Svg_DIR` configure argument: the installed Qt Android Widgets dependency
  graph needs the Qt Svg package to configure successfully.
- Keep `VaultEntry::salt` and its serialization. Although the UI does not
  populate it, the public vault serializer and tests currently use it, and
  removing it would change encrypted serialized data.
- Keep the plaintext website index and encrypted website values. The
  duplication enables website search while the vault is locked.
- Remove the desktop `AuthQtApp` CTest registration: it launches the normal
  interactive event loop and times out instead of acting as a test. Continue
  building `AuthQt` as part of the desktop build.

Do not broaden cleanup into cryptographic algorithm changes, file-format
changes, UI redesign, or QR Sync work.

### Documentation

- Keep the README concise and user-facing. Include every supported Make target,
  what it does, target-specific preflight behavior, required overrides, and the
  desktop/Android outputs. Do not include direct CMake or CTest build commands.
- Make `tests/README.md` use the Make targets and focus on test scope rather
  than repeating configure instructions.
- Make `Agents.md` a technical map for future code changes: components, data
  flow, key invariants, storage/security boundaries, build/preflight behavior,
  and areas that must not be changed without an explicit request. Remove its
  outdated direct CMake build commands.
- Remove the `Agents.md` ignore entry from `.gitignore` so the requested
  documentation can be tracked; do not stage it.

## Failure behavior

If a prerequisite needed by the requested target is missing or misconfigured,
print all failed checks for that target's profile and stop before its work.
This lets `help` and cleanup targets run without unrelated build toolchains.

If a configured path is missing, report the exact variable/path and show the
corresponding Make variable or environment variable to set. Do not silently
switch to another Qt or NDK installation.

## Acceptance criteria

1. Every build, test, run, and packaging target checks its needed prerequisites before target work; `all` checks both desktop and Android prerequisites.
2. Missing prerequisites for the selected target are all reported with a cross, and the Make command exits before running its target; a complete environment prints successful checks and continues. `help`, `clean`, and `android-clean` do not require build toolchains.
3. `make build`, `make android`, and `make all` retain their respective
   desktop-only, Android-only, and sequential combined behavior.
4. `make all` does not run desktop and Android builds concurrently.
5. No QR Sync source file changes.
6. The selected cleanup removes duplication or unused scaffolding without
   changing app behavior, authentication behavior, or the password-vault file
   format.
7. README lists all Make commands without direct CMake/CTest build commands;
   `Agents.md` contains technical code knowledge and is no longer ignored.
8. No commit or push is created.
