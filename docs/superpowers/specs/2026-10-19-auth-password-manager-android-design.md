# Auth, Password Manager, and Android APK Design

## Goal

Make the Qt application enforce the Auth registration rules, unlock feature tabs
only after a successful login, replace the password manager prototype with an
encrypted persistent credential vault, and build an Android APK.

## Current behavior

- `AuthTab` stores account salts and protocol payloads in per-widget in-memory
  maps. Registration assigns by username, so a repeat registration overwrites
  the existing account. Auth state is lost when the application exits.
- `MainWindow` always adds Auth, Password Manager, and QR Sync tabs.
- `PasswordManagerTab` generates random credential passwords, does not store a
  master password verifier, and keeps its encrypted blob and decrypted entries
  only in memory. Its Retrieve action reveals a credential in a message box.
- `CMakeLists.txt` uses desktop-specific dependency paths and libraries, and
  builds tests against the host configuration. The Android Make target requests
  an ABI option inconsistent with the CMake Android configuration and does not
  package an APK.
- Qt 6.12 Android kits, Android SDK platforms/build tools, and NDK r30 are
  installed. The project currently has host-built OpenSSL, liboqs, and Argon2
  dependencies only; Argon2 is also missing from the vcpkg manifest.

## Approved behavior

### Authentication and feature access

- Reject registration when the username already exists in the current process;
  preserve the original credentials and display an actionable message.
- Before invoking registration, require at least eight characters, one special
  character, one uppercase ASCII letter, one lowercase ASCII letter, and one
  digit. Keep the cryptographic registration API usable with arbitrary byte
  strings for protocol tests and non-UI callers; enforce this product policy at
  the Auth registration boundary.
- Account data remains in memory for the current application run. Registration
  does not unlock feature tabs. A successful login makes Password Manager and QR
  Sync visible and selectable. A failed login leaves them hidden.
- Keep `QRSyncTab` implementation and behavior unchanged. Its only change in
  behavior is that users cannot reach it until login succeeds.

### Password manager

- Replace the current password manager UI with explicit setup, add, and view
  states.
- If no vault exists, show only the master-password setup view. After the
  master password is set, hide setup and show the credential-add workflow.
- A credential consists of the website URL, username, and user-entered password.
  Do not generate or substitute a password.
- Persist the vault under the Qt application-specific data directory. Store the
  salt, KDF parameters, and AES-256-GCM encrypted vault payload; never persist
  usernames, passwords, or the master password. Store a separate plaintext
  website URL index so websites can be listed and searched while locked. Write
  the vault payload and index atomically as one file.
- Use the existing Argon2id key derivation and AES-256-GCM vault code. Wrong
  master passwords and modified vault files must fail closed without exposing
  partial plaintext entries.
- Provide a search field and a list of saved websites. Request the master
  password the first time a user reveals credentials in a session. A successful
  entry starts a fixed ten-minute session measured with a monotonic clock; after
  expiry, hide username/password values and require the master password again.
- For a revealed credential, provide separate username and password copy
  actions and a website-link action. Normalize missing schemes to `https://`,
  accept only valid HTTP/HTTPS URLs, and open them through Qt's system URL
  handler.

### Android package

- Configure the Qt Widgets application for Android arm64-v8a using the installed
  Qt Android kit, Android SDK, and NDK.
- Build OpenSSL, liboqs, and Argon2 for the Android target ABI through the
  project dependency configuration; remove hardcoded host paths from targets
  that must cross-compile. Add Argon2 to the declared dependency manifest.
- Provide a Makefile target that configures, compiles, and packages an installable
  APK. Keep desktop targets functional.
- Do not modify QR Sync source as part of Android packaging.

## Data and security decisions

- Account uniqueness is case-sensitive, matching the existing map key behavior.
- Password policy counts UTF-8 input as entered for minimum length and checks
  the required character classes using ASCII classes.
- The vault is device-local and shared by the app, not partitioned by Auth
  username. Account persistence and cross-device vault synchronization are out
  of scope.
- The ten-minute reveal window is absolute from the first successful master
  password entry for viewing; activity does not extend it.
- The website list and search remain available while locked, but usernames and
  passwords remain hidden. Website URLs are intentionally visible in the local
  app data file to support this behavior.
- Clipboard contents are not automatically cleared; copy actions are explicit.

## Failure handling

- Duplicate usernames and policy violations must not modify either account map.
- Failed login must not reveal feature tabs.
- Vault setup, encryption, decryption, parsing, or disk-write failures must be
  shown without replacing a previously valid vault file.
- Invalid URLs must not be opened.
- If Android dependency configuration cannot produce target libraries or Qt
  packaging tools are unavailable, report the exact failing prerequisite and
  command rather than claiming an APK was built.

## Acceptance criteria

1. Existing usernames cannot be overwritten through the Qt registration UI.
2. Registration accepts passwords meeting all five policy requirements and
   rejects passwords missing any one requirement.
3. Password Manager and QR Sync are hidden until successful login and available
   after it.
4. The password manager setup screen has no credential controls before setup;
   after setup, users can add the website, username, and password they entered.
5. Encrypted credential entries survive application restart and remain
   unreadable without the correct master password; the website URL index
   remains readable so the app can list and search sites while locked.
6. Search filters saved websites; first reveal requires the master password;
   subsequent reveals do not prompt during the fixed ten-minute window; expiry
   hides secrets and requires authentication again.
7. Username and password copy actions copy their respective values, and valid
   website URLs open externally.
8. Existing QR Sync source and behavior remain unchanged.
9. The Android Make target produces an arm64-v8a APK, and the desktop CMake
   configuration remains available.

## Out of scope

- Persisting Auth accounts or changing the authentication protocol.
- Implementing QR code generation, scanning, sync, or protocol changes.
- Adding clipboard auto-clear, browser integration beyond opening URLs, or
  credential sharing.
- Signing a production release APK with a user-owned signing key.
