# Auth Registration and Feature Gating Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Prevent Auth account overwrite, enforce the requested registration password policy, and keep Password Manager and QR Sync unavailable until login succeeds.

**Architecture:** Keep the protocol library byte-oriented and unchanged. Apply UI registration rules before calling `RegisterUser`; signal successful login from `AuthTab` to `MainWindow`, which reveals the existing feature tabs.

**Tech Stack:** C++17, Qt 6 Widgets, existing Auth protocol library.

**Spec:** [2026-10-19-auth-password-manager-android-design.md](../specs/2026-10-19-auth-password-manager-android-design.md)

## Global Constraints

- “Account data remains in memory for the current application run.”
- “Before invoking registration, require at least eight characters, one special character, one uppercase ASCII letter, one lowercase ASCII letter, and one digit.”
- “A successful login makes Password Manager and QR Sync visible and selectable. A failed login leaves them hidden.”
- “Keep `QRSyncTab` implementation and behavior unchanged.”
- Do not add or run automated tests unless requested; compile the affected application targets for verification.
- Do not commit or push.

## Review Focus

- Duplicate registration preserves the existing account and does not replace its salt or payload.
- Password length counts Unicode scalar characters; uppercase, lowercase, and digit classes are ASCII; special means ASCII punctuation (not whitespace).
- Missing any one required character class rejects registration before protocol registration.
- Failed login and unknown usernames leave feature tabs hidden.
- Successful registration alone leaves feature tabs hidden; a subsequent successful login reveals them.

---

### Task 1: Protect Auth registration

**Files:**
- Modify: `ui/AuthTab.cpp`

**Interfaces:**
- Consumes: existing `auth::RegisterUser()` and the per-tab `user_db_` / `server_db_` maps.
- Produces: registration UI flow that rejects duplicate usernames and invalid passwords before either map is changed.

- [x] **Step 1: Add a local password-policy helper**

  Implement `QString registrationPasswordError(const QString& password)` in `ui/AuthTab.cpp`. Return an empty string for valid input; otherwise return a concise reason. Count `password.toUcs4().size()` and require at least eight Unicode scalar values. Check ASCII uppercase, lowercase, digit, and punctuation classes.

- [x] **Step 2: Reject duplicate usernames before generating secrets**

  In `AuthTab::onRegisterClicked()`, check `server_db_.find(user.toStdString())` before generating `R` or calling `RegisterUser`. On a match, show a warning, preserve both maps, and return.

- [x] **Step 3: Enforce the policy before calling `RegisterUser()`**

  Call `registrationPasswordError()` before `secureInput()`. Display the returned reason and return without changing either map when invalid. Keep the protocol API unchanged for existing callers.

- [x] **Step 4: Compile the desktop Auth UI**

  Run: `cmake --build build --target AuthQt`

  Expected: `AuthQt` compiles successfully.

### Task 2: Reveal feature tabs after successful login

**Files:**
- Modify: `ui/AuthTab.h`
- Modify: `ui/AuthTab.cpp`
- Modify: `ui/MainWindow.cpp`

**Interfaces:**
- Consumes: `AuthTab` login result.
- Produces: `AuthTab::authenticationSucceeded()` Qt signal emitted only after `AuthenticateUser()` returns true; `MainWindow` uses it to reveal Password Manager and QR Sync.

- [x] **Step 1: Add the success signal**

  Declare `void authenticationSucceeded();` under `signals:` in `AuthTab.h`. Emit it only inside the successful branch of `AuthTab::onLoginClicked()`.

- [x] **Step 2: Hide gated tabs until the signal fires**

  In `MainWindow.cpp`, keep the existing tabs and their order, hide indices 1 and 2 after adding them, and connect `AuthTab::authenticationSucceeded()` to a lambda that makes both tabs visible. Do not change or edit `QRSyncTab` files.

- [x] **Step 3: Compile the desktop Auth UI**

  Run: `cmake --build build --target AuthQt`

  Expected: `AuthQt` compiles successfully with the signal/slot connection.

---
